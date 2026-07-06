#!/usr/bin/env Rscript

all_args <- commandArgs(trailingOnly = FALSE)
script_arg <- grep("^--file=", all_args, value = TRUE)
if (length(script_arg) > 0) {
  script_path <- normalizePath(sub("^--file=", "", script_arg[[1]]), mustWork = FALSE)
  local_lib <- normalizePath(file.path(dirname(script_path), "..", "..", ".r-lib"), mustWork = FALSE)
  if (dir.exists(local_lib)) {
    .libPaths(c(local_lib, .libPaths()))
  }
}

args <- commandArgs(trailingOnly = TRUE)

option_value <- function(name, default = NULL) {
  idx <- match(name, args)
  if (is.na(idx) || idx == length(args)) {
    return(default)
  }
  args[[idx + 1]]
}

events_path <- option_value("--events")
out_path <- option_value("--out")
if (is.null(events_path) || is.null(out_path)) {
  stop("usage: train_iforest.R --events <events.json> --out <model.json>")
}
if (!requireNamespace("jsonlite", quietly = TRUE)) {
  stop("jsonlite is required for FastR retraining")
}

events <- jsonlite::fromJSON(events_path, simplifyVector = FALSE)
if (length(events) == 0) {
  stop("cannot train model from empty event list")
}

status_idx <- function(code) {
  key <- as.character(code)
  if (key == "200") return(0)
  if (key == "403") return(1)
  if (key == "404") return(2)
  if (key == "500") return(3)
  -1
}

event_field <- function(event, name, default) {
  value <- event[[name]]
  if (is.null(value)) default else value
}

timestamps <- vapply(events, function(e) {
  as.numeric(as.POSIXct(event_field(e, "timestamp", "1970-01-01T00:00:00"), tz = Sys.timezone()))
}, numeric(1))
ips <- vapply(events, function(e) event_field(e, "ip", ""), character(1))
statuses <- vapply(events, function(e) as.integer(event_field(e, "status_code", 0)), integer(1))
exempt <- vapply(events, function(e) isTRUE(event_field(e, "exempt_path", FALSE)), logical(1))

feature_names <- c(
  "burst_count",
  "kw_hits",
  "method_is_post",
  "path_depth",
  "path_len",
  "response_time_ms",
  "status_code",
  "status_idx",
  "total_404"
)

matrix <- matrix(0, nrow = length(events), ncol = length(feature_names))
colnames(matrix) <- feature_names
for (i in seq_along(events)) {
  event <- events[[i]]
  path <- event_field(event, "path", "/")
  ip <- event_field(event, "ip", "")
  method <- event_field(event, "method", "GET")
  burst <- sum(ips == ip & abs(timestamps - timestamps[[i]]) <= 10)
  total_404 <- sum(ips == ip & statuses == 404 & !exempt)
  parts <- strsplit(path, "/", fixed = TRUE)[[1]]
  path_depth <- sum(nzchar(parts))

  matrix[i, "burst_count"] <- burst
  matrix[i, "kw_hits"] <- 0
  matrix[i, "method_is_post"] <- ifelse(toupper(method) == "POST", 1, 0)
  matrix[i, "path_depth"] <- path_depth
  matrix[i, "path_len"] <- nchar(path)
  matrix[i, "response_time_ms"] <- as.numeric(event_field(event, "response_time_ms", 0))
  matrix[i, "status_code"] <- statuses[[i]]
  matrix[i, "status_idx"] <- status_idx(statuses[[i]])
  matrix[i, "total_404"] <- total_404
}

euler_gamma <- 0.5772156649015329
c_factor <- function(n) {
  if (n <= 1) return(0)
  if (n == 2) return(1)
  2 * (log(n - 1) + euler_gamma) - (2 * (n - 1) / n)
}

build_tree <- function(data, depth, max_depth, feature_subset) {
  if (nrow(data) <= 1 || depth >= max_depth) {
    return(list(leaf = TRUE, leaf_size = nrow(data)))
  }
  shuffled <- sample(feature_subset, length(feature_subset), replace = FALSE)
  chosen <- NA
  min_value <- 0
  max_value <- 0
  for (feature in shuffled) {
    values <- data[, feature + 1]
    values <- values[is.finite(values)]
    if (length(values) > 0 && min(values) < max(values)) {
      chosen <- feature
      min_value <- min(values)
      max_value <- max(values)
      break
    }
  }
  if (is.na(chosen)) {
    return(list(leaf = TRUE, leaf_size = nrow(data)))
  }
  split <- min_value + runif(1) * (max_value - min_value)
  values <- data[, chosen + 1]
  left_idx <- is.finite(values) & values < split
  if (sum(left_idx) == 0 || sum(!left_idx) == 0) {
    return(list(leaf = TRUE, leaf_size = nrow(data)))
  }
  list(
    leaf = FALSE,
    feature = chosen,
    split = split,
    left = build_tree(data[left_idx, , drop = FALSE], depth + 1, max_depth, feature_subset),
    right = build_tree(data[!left_idx, , drop = FALSE], depth + 1, max_depth, feature_subset)
  )
}

path_length <- function(row, node, depth) {
  if (isTRUE(node$leaf)) {
    return(depth + c_factor(node$leaf_size))
  }
  value <- row[[node$feature + 1]]
  if (is.finite(value) && value < node$split) {
    return(path_length(row, node$left, depth + 1))
  }
  path_length(row, node$right, depth + 1)
}

set.seed(42)
n_trees <- 100
sample_size <- min(256, nrow(matrix))
if (sample_size < 2) {
  sample_size <- 2
}
sample_size <- min(sample_size, nrow(matrix))
max_depth <- ceiling(log2(sample_size))
feature_subset <- seq_len(ncol(matrix)) - 1
trees <- vector("list", n_trees)
for (i in seq_len(n_trees)) {
  rows <- sample(seq_len(nrow(matrix)), sample_size, replace = FALSE)
  trees[[i]] <- list(
    feature_subset = as.list(feature_subset),
    root = build_tree(matrix[rows, , drop = FALSE], 0, max_depth, feature_subset)
  )
}

scores <- vapply(seq_len(nrow(matrix)), function(i) {
  path_sum <- sum(vapply(trees, function(tree) path_length(matrix[i, ], tree$root, 0), numeric(1)))
  path_mean <- path_sum / length(trees)
  if (c_factor(sample_size) <= 0) 0 else 2^(-path_mean / c_factor(sample_size))
}, numeric(1))
contamination <- 0.05
threshold <- sort(scores)[max(1, min(length(scores), floor((1 - contamination) * (length(scores) - 1)) + 1))]

status_counts <- as.list(table(statuses))
names(status_counts) <- names(table(statuses))

model <- list(
  model_type = "isolation-forest",
  model_schema = "iforest-v1",
  backend = "fastr_aiwaf",
  feature_names = as.list(feature_names),
  sample_size = sample_size,
  trees = trees,
  contamination = contamination,
  threshold = threshold,
  anomaly_count = sum(scores >= threshold),
  samples = length(events),
  avg_response_time_ms = mean(matrix[, "response_time_ms"]),
  status_counts = status_counts,
  behavior = list(),
  metadata = list(
    model_backend = "fastr_aiwaf",
    model_schema = "iforest-v1",
    created_at_epoch_ms = as.numeric(Sys.time()) * 1000
  )
)

jsonlite::write_json(model, out_path, auto_unbox = TRUE, digits = NA)

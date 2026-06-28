package com.aiwaf.servlet;

import com.aiwaf.core.AiwafLoggingCore;
import com.aiwaf.core.AiwafRequest;
import com.aiwaf.core.AiwafDecision;
import com.aiwaf.core.AiwafEngine;
import com.aiwaf.core.ServletRequestMapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public final class AiwafServletFilter implements Filter {
    private final AiwafEngine engine;

    public AiwafServletFilter(AiwafEngine engine) {
        this.engine = engine;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpReq) || !(response instanceof HttpServletResponse httpResp)) {
            chain.doFilter(request, response);
            return;
        }
        long start = System.currentTimeMillis();
        AiwafRequest aiwafReq = ServletRequestMapper.from(httpReq);
        AiwafDecision decision = engine.evaluate(aiwafReq);
        if (!decision.allowed()) {
            httpResp.sendError(decision.statusCode(), decision.reason());
            AiwafLoggingCore.log(engine.config(), aiwafReq, decision, decision.statusCode(), System.currentTimeMillis() - start, 0);
            return;
        }
        chain.doFilter(request, response);
        AiwafLoggingCore.log(engine.config(), aiwafReq, decision, httpResp.getStatus(), System.currentTimeMillis() - start, 0);
    }
}

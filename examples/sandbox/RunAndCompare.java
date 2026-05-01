public final class RunAndCompare {
    public static void main(String[] args) {
        System.out.println("Compile and run manually in this order:");
        System.out.println("  javac --release 17 AttackSuite.java CompareResults.java CompareResultsModes.java RunAndCompare.java");
        System.out.println("  java AttackSuite http://127.0.0.1:3001 direct normal");
        System.out.println("  java AttackSuite http://127.0.0.1:3001 direct attacks");
        System.out.println("  java AttackSuite http://localhost:8080 protected_java normal");
        System.out.println("  java AttackSuite http://localhost:8080 protected_java attacks");
        System.out.println("  java AttackSuite http://localhost:8081 protected_spring normal");
        System.out.println("  java AttackSuite http://localhost:8081 protected_spring attacks");
        System.out.println("  java CompareResults results_direct_*.json results_protected_*.json");
        System.out.println("  java CompareResultsModes results_protected_java_normal_*.json results_protected_spring_normal_*.json -- results_protected_java_attacks_*.json results_protected_spring_attacks_*.json");
    }
}

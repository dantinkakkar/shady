package shady.example;

import org.apache.calcite.runtime.SqlFunctions;

/** A normal application using only a public API from its declared OSS dependency. */
public final class CurrentCalciteApp {
    private CurrentCalciteApp() {
    }

    public static void main(String[] args) {
        System.out.println("CURRENT_CALCITE_APP_STARTED");
        boolean found = SqlFunctions.containsSubstr(
                "Shady finds regressions", "REGRESSIONS");
        System.out.println("CALCITE_RESULT=" + found);
    }
}

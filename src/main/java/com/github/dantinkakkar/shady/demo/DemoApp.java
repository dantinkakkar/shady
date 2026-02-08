package com.github.dantinkakkar.shady.demo;

/**
 * Simple demo application to show the agent in action.
 */
public class DemoApp {
    public static void main(String[] args) {
        System.out.println("Demo application started.");
        System.out.println("If the agent is loaded, you should see Shady messages above.");
        System.out.println("To run with the agent: java -javaagent:target/shady-1.0-SNAPSHOT.jar -cp target/shady-1.0-SNAPSHOT.jar com.github.dantinkakkar.shady.demo.DemoApp");
    }
}

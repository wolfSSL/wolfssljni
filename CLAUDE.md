
# Building wolfSSL JNI/JSSE (wolfssljni)
- To build the native JNI shared library run "./java.sh"
- To build the Java JAR library run "ant"
- To build the JNI/JSSE examples run "ant examples"

# Running JUnit tests
- To run JUnit tests run "ant test"
- All tests should pass without problems

# Code Style
- Keep lines under 80 characters maximum length
- Only use multi-line comments, no "//" style ones
- Remove any trailing white space
- Use 4 spaces for one tab, no hard tabs

# Source Code Organization
- The source code is organized into the following directories:
  - native: JNI source and header files
  - src: Java source code
  - src/java/com/wolfssl: com.wolfssl package JNI layer source code
  - src/java/com/wolfssl/provider/jsse: com.wolfssl.provider.jsse package wolfJSSE source code
  - src/test: JUnit test code
  - src/test/com/wolfssl/test: com.wolfssl thin JNI wrapper JUnit test code
  - src/test/com/wolfssl/provider/jsse/test: com.wolfssl.provider.jsse wolfJSSE provider JUnit test code
  - build.xml: Ant build file
  - pom.xml: Maven build file
  - docs: Generated Javadoc files
  - scripts/infer.sh: Script to run Facebook Infer static analysis
  - IDE/Android: Android Studio example project files

# Workflow
- Make sure package compiles and all JUnit tests pass when you are making code changes
- Maintain minimum Java compatibility down to Java 8

# Example Code Guidelines for Writing New Code
- All examples are placed under the "examples" directory
- "examples/README.md" contains a list of examples and basic instructions
- Directory "examples" contains JNI-level examples
- Directory "examples/provider" contains JSSE-level examples
- All examples should have two files:
  - Example.java: Java source code
  - Example.sh: Shell script to run the example
- Examples will be run from the root directory
- Example .jks files are located under "examples/provider"
- Example .jks files are updated using the update-jks.sh script
- RMI examples using wolfJSSE are under "examples/provider/rmi"
- JSSE level examples do not need to call WolfSSL.loadLibrary(), that is called automatically inside wolfJSSE
- JNI level examples do need to call WolfSSL.loadLibrary()


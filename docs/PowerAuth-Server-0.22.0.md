# Migration from 0.21.0 to 0.22.0

This guide contains instructions for migration from PowerAuth Server version `0.21.0` to version `0.22.0`.

## Java 11 Support

Java 11 no longer supports installing Bouncy Castle using library extension mechanism. PowerAuth no 
longer contains the Bouncy Castle library in war files to avoid classloader issues in some web containers (e.g. Tomcat). 

The Bouncy Castle provider needs to be installed using mechanism supported by the web container. 
See the [Installing Bouncy Castle](./Installing-Bouncy-Castle.md#installing-bouncy-castle-on-java-11) chapter in documentation.


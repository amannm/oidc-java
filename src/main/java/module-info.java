module systems.cauldron.utility.example {
    requires java.net.http;
    requires java.json;
    requires org.apache.logging.log4j;
    exports systems.cauldron.utility;
    exports systems.cauldron.utility.jwt;
    exports systems.cauldron.utility.jwt.jws;
    exports systems.cauldron.utility.oidc;
}
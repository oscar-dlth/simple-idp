const express = require("express");
const xmlbuilder = require("xmlbuilder");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();
app.use(express.urlencoded({ extended: true }));

// Certificados (para firmar tokens)
const privateKey = fs.readFileSync("src/cert/private.key", "utf8"); // Clave privada
const publicCert = fs.readFileSync("src/cert/certificate.crt", "utf8"); // Certificado público

// Configuración del IdP
const ENTITY_ID = "https://www.carindth.com";
const PASSIVE_REQUESTOR_ENDPOINT = "https://www.carindth.com/wsfed";

// Endpoint de metadatos
app.get("/metadata", (req: any, res: any) => {
  // Construir XML de metadatos
  const metadata = xmlbuilder.create("EntityDescriptor", {
    encoding: "utf-8",
  })
    .att("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata")
    .att("entityID", ENTITY_ID)
    .ele("IDPSSODescriptor", { protocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol" })
    .ele("KeyDescriptor", { use: "signing" })
    .ele("KeyInfo", { xmlns: "http://www.w3.org/2000/09/xmldsig#" })
    .ele("X509Data")
    .ele("X509Certificate", publicCert.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, ""))
    .up().up().up().up()
    .ele("SingleSignOnService", {
      Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
      Location: PASSIVE_REQUESTOR_ENDPOINT,
    })
    .end({ pretty: true });

  // Responder con el XML de metadatos
  res.set("Content-Type", "application/xml");
  res.send(metadata);
});

// Endpoint principal de WS-Fed
app.get("/wsfed", (req: any, res: any) => {
  const wtrealm = req.query.wtrealm; // URL confiable del RP
  const wreply = req.query.wreply; // Endpoint de retorno del RP

  // Renderizar una página de inicio de sesión simple
  res.send(`
    <form action="/wsfed/login" method="POST">
      <input type="hidden" name="wtrealm" value="${wtrealm}" />
      <input type="hidden" name="wreply" value="${wreply}" />
      <input type="text" name="username" placeholder="Usuario" required />
      <input type="password" name="password" placeholder="Contraseña" required />
      <button type="submit">Iniciar sesión</button>
    </form>
  `);
});

// Procesar el inicio de sesión
app.post("/wsfed/login", (req: any, res: any) => {
  const { username, password, wtrealm, wreply } = req.body;

  // Autenticar usuario (reemplazar con tu lógica de autenticación)
  if (username === "user" && password === "password") {
    // Claims para el token
    const claims = {
      sub: username,
      email: `${username}@example.com`,
      roles: ["User"],
    };

    // Crear un token SAML firmado
    const samlToken = jwt.sign(claims, privateKey, { algorithm: "RS256", expiresIn: "1h" });

    // Construir la respuesta WS-Fed
    const response = xmlbuilder.create("samlp:Response", { encoding: "utf-8" })
    .att("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
    .att("Version", "2.0")
    .ele("saml:Assertion")
      .ele("saml:Subject")
        .ele("saml:NameID", username).up() // Move back to <saml:Subject>
      .up() // Move back to <saml:Assertion>
      .ele("saml:AttributeStatement")
        .ele("saml:Attribute")
          .att("Name", "email")
          .ele("saml:AttributeValue", claims.email).up() // Move back to <saml:Attribute>
        .up() // Move back to <saml:AttributeStatement>
      .up() // Move back to <saml:Assertion>
    .up() // Move back to <samlp:Response>
    .end({ pretty: true });

    // Responder con el token SAML dentro de un formulario
    res.send(`
      <form action="${wreply}" method="POST">
        <input type="hidden" name="wresult" value="${response}" />
        <input type="hidden" name="wctx" value="${wtrealm}" />
        <button type="submit">Continuar</button>
      </form>
    `);
  } else {
    res.status(401).send("Credenciales inválidas.");
  }
});

// Iniciar servidor
export default app;
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

// Endpoint WS-FED Passive
app.get("/wsfed", (req: any, res: any) => {
  const { code, state, session_state } = req.query;

  // Verificar si el usuario está autenticado
  if (!req.cookies?.session) {
    // Redirigir al formulario de inicio de sesión si no hay sesión activa
    return res.redirect(`/login?state=${state}`);
  }

  // Generar y firmar el token (usuario ya autenticado)
  const securityToken = jwt.sign(
    {
      aud: "your-rp-audience",
      iss: 'https://www.carindth.com',
      sub: req.cookies.session.user, // Usuario autenticado
    },
    privateKey,
    { algorithm: "RS256", expiresIn: "1h" }
  );

  // Construir y enviar la respuesta WS-FED
  res.set("Content-Type", "application/x-www-form-urlencoded");
  res.send(
    `<html>
      <body onload="document.forms[0].submit()">
        <form method="post" action="${state}" enctype="application/x-www-form-urlencoded">
          <input type="hidden" name="wctx" value="${state}" />
          <input type="hidden" name="wresult" value="${securityToken}" />
        </form>
      </body>
    </html>`
  );
});

// Endpoint para el formulario de inicio de sesión
app.get("/login", (req: any, res: any) => {
  const { state } = req.query;

  res.send(`
    <html>
      <body>
        <form method="post" action="/login">
          <input type="hidden" name="state" value="${state}" />
          <label>Usuario:</label>
          <input type="text" name="username" required />
          <label>Contraseña:</label>
          <input type="password" name="password" required />
          <button type="submit">Iniciar Sesión</button>
        </form>
      </body>
    </html>
  `);
});

const users = [
  { username: "user1", password: "password1" }, // Usuarios de ejemplo
  { username: "user2", password: "password2" },
];
// Endpoint para procesar el inicio de sesión
app.post("/login", (req: any, res: any) => {
  const { username, password, state } = req.body;

  // Verificar credenciales del usuario
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).send("Usuario o contraseña incorrectos.");
  }

  // Crear una sesión (ejemplo simple con cookies)
  res.cookie("session", { user: username }, { httpOnly: true });

  // Redirigir al flujo original
  res.redirect(`/wsfed?state=${state}`);
});

// Iniciar servidor
export default app;
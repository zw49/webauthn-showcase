const express = require("express");
const { Attestation, GetAttestationResult, Assertion, GetAssertionResult } = require("./fido2");
const { encode, decode } = require("base64-arraybuffer");

const db = {};
const challenges = {};

const user = {
  username: "test_user",
  id: "test_id",
};

const PORT = process.env.PORT || 3001;

const app = express();
app.use(express.json());



// above the listen func
app.get("/api", (req, res) => {
  res.json({ message: "Hello from the server1." });
});

app.get("/attestate/begin", async (req, res) => {
  Attestation(user).then((data) => {
    res.json(data);
    challenges[user.id] = data.challenge;
  });
});

app.post("/attestate/end", async (req, res) => {
  const attestation = req.body;
  GetAttestationResult(attestation, challenges[user.id]).then((data) => {
    user.rawId = data.credentialId;
    user.publicKey = data.publicKey;
  });
  res.status(201).json({ message: "Credential created" });
});

app.get("/assert/begin", async (req, res) => {
    Assertion(user).then(data => {
        res.json(data);
        challenges[user.id] = data.challenge;
    })
  });

  app.post("/assert/end", async (req, res) => {
    const assertion = req.body;
    GetAssertionResult(assertion, challenges[user.id], user).then((data) => {
        res.json({ message: "Authenticated Successfully!" });
    }).catch((data)=> {
        res.status(401).json({ error: "Authentication Unsuccessful" });
    });
  });

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});

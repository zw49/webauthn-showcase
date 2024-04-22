const { Fido2Lib } = require("fido2-lib");
const { encode, decode } = require("base64-arraybuffer");

const fido2 = new Fido2Lib({
  timeout: 30 * 1000,
  rpId: "localhost",
  rpName: "webauthn-test",
  challengeSize: 128,
  attestation: "direct",
  cryptoParams: [-7, -257],
  authenticatorAttachment: "cross-platform",
  authenticatorUserVerification: "discouraged",
  authenticatorRequireResidentKey: false,
});

const GetChallenge = () => {
  const options = fido2.assertionOptions();
  return options;
};

const Attestation = async (user) => {
  const options = await fido2.attestationOptions();
  
  options.user = {
    id: user.id,
    name: user.username,
    displayName: user.username,
  };

  const encoded = {
    ...options,
    challenge: encode(options.challenge),
    userVerification: 'preferred',

  };
  return encoded;
};


const Assertion = async (user) => {

    const options = await fido2.assertionOptions();

    const encoded = {
        ...options,
        userVerification: 'preferred',
        challenge: encode(options.challenge),
        allowCredentials: [{
            type: "public-key",
            id: user.rawId,
            transports: ["usb", "ble", "nfc"]
        }]
    };

  return encoded;
};

const GetAttestationResult = async (attestation, challenge) => {
    const result = await fido2.attestationResult({
        ...attestation,
        rawId: decode(attestation.rawId)
    }, {
        rpId: "localhost",
        challenge, // get the previously stored challenge
        origin: "http://localhost:3000",
        factor: "either"
    });

    return {credentialId: encode(result.clientData.get("rawId")), publicKey: result.authnrData.get("credentialPublicKeyPem")};
}

const GetAssertionResult = async (assertion, challenge, user) => {
    const result = await fido2.assertionResult({
        ...assertion,
        rawId: decode(assertion.rawId),
        response: {
            ...assertion.response,
            authenticatorData: decode(assertion.response.authenticatorData)
        }
    }, {
        challenge, // get the previously stored challenge
        origin: "http://localhost:3000",
        factor: "either",
        publicKey: user.publicKey, // get the previously stored public key
        prevCounter: 0,
        userHandle: null
    });

    return result;
}

module.exports = {
  GetChallenge,
  Attestation,
  GetAttestationResult,
  Assertion,
  GetAssertionResult
};

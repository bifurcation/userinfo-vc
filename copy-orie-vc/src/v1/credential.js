const schema = require('./schema');

const externalProof = require('./external-proof');
const proof = externalProof.credential;

class Credential {
    constructor(input) {
        const {valid, errors} = schema.validate(schema.credentialSchema, input);
        if (!valid) {
            const message = `
            Could not create credential.
            
            Type Error:
            
            ${JSON.stringify(errors, null, 2)}
            `;
                    throw new Error(message);
        }
    }

    toJSON() {
        let output = {};
    }
}
// config.js
require('dotenv').config();

const fetchPublicKey = () => {
    return process.env.PUBLIC_KEY ? Buffer.from(process.env.PUBLIC_KEY, 'base64').toString('ascii') : '';
};

const fetchPrivateKey = () => {
    return process.env.PRIVATE_KEY ? Buffer.from(process.env.PRIVATE_KEY, 'base64').toString('ascii') : '';
};

const appUrl = process.env.APP_URL || 'http://localhost:3000';
const entityId = process.env.ENTITY_ID || 'https://saml.example.com/entityid/example.com';
const privateKey = fetchPrivateKey();
const publicKey = fetchPublicKey();

const config = {
    appUrl,
    entityId,
    privateKey,
    publicKey,
};

const getEntityId = (entityId, namespace) => {
    //return namespace ? `${entityId}/${namespace}` : entityId;
    return entityId;
};

// const getSSOUrl = (appUrl, namespace) => {
//     return `${appUrl}/api`  + '/saml/sso';
// };

const getSSOUrl = (appUrl, namespace) => {
    if (!appUrl || !namespace) {
        console.error('getSSOUrl called with undefined appUrl or namespace');
        return '/error'; // fallback error route or handle this case appropriately
    }
    return `${appUrl}/api/saml/sso`;
};


module.exports = {
    config,
    getEntityId,
    getSSOUrl
};
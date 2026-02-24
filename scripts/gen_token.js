const jwt = require('jsonwebtoken');
require('dotenv').config();

const payload = {
    id: '93c58807-e657-4403-94a1-d8036cbd1bf3',
    username: 'testadmin',
    email: 'testadmin@vpsphere.local',
    plan_id: 1
};

const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
console.log(token);

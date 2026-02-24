#!/bin/bash
cd /home/tushar/deployment-engine-1
TOKEN=$(node scripts/gen_token.js | tail -n 1)
curl -X POST http://localhost:5000/api/deployments/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "repoUrl": "https://github.com/expressjs/express",
    "projectName": "express-test",
    "branch": "master",
    "deploymentType": "web_service"
  }'

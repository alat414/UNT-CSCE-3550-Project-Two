/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Environment testing variables
*           constructed and paths listed
*           testsEnvironment.cpp
************************************************* */

require('dotenv').config({path: '.env.test'});

process.env.ACCESS_TOKEN_SECRET = 'test-access-secret';
process.env.REFRESH_TOKEN_SECRET = 'test-refresh-secret';
process.env.PORT = 8082;

const request = require('supertest');
const { app } = require('../../keyExpiry');

module.exports = {request, app};
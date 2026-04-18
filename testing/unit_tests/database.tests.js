/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: Project One JWKS server
*  Purpose: Database testing functions
*           using functions and calls to ensure
*           database actions including opening,
*           creating, and connections are working
*           correctly. 
*           database.tests.js
************************************************* */

const sqlite3 = require('sqlite3');
const path = require('path');
const fs = require('fs');
/*
 * Copyright (c) Why Not Soluciones, S.L.
 */

/*jslint node: true */
/*jshint -W030 */
"use strict";

var security = require('../'),
  expect = require('chai').expect;

describe('Security module unit tests', function () {

  describe('allow', function () {
    it('Root Should be allowed to run actions of any access level', function (done) {
      var accessLevel;
      var user = {
        role: security.userRoles.root
      };
      for (accessLevel in security.accessLevels) {
        expect(security.allow(user, security.accessLevels[accessLevel])).to.be.true;
      }
      done();
    });

    it('Public users Should be allowed to run action of public access level', function (done) {
      var accessLevel;
      var user = {
        role: security.userRoles.public
      };
      for (accessLevel in security.accessLevels) {
        if (accessLevel === 'public') {
          expect(security.allow(user, security.accessLevels[accessLevel])).to.be.true;
        } else {
          expect(security.allow(user, security.accessLevels[accessLevel])).to.be.false;
        }
      }
      done();
    });
  });

  describe('allow', function () {
    it('Should do md5 hash of string', function (done) {
      expect(security.md5('1longpasS_woRd')).to.be.equal('9aa233262fb48be9b07230f3c8ff6b94');
      done();
    });
  });

});

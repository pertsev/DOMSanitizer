/* global casper */

var url = 'http:/localhost:9000/tmp/samples/page.html';

casper.test.begin('False Positive tests for JSLoose', function suite(test) {
    casper.start();

    var suite = require('specLoose/jsl.spec.js');
    suite.tests.forEach(function(ctest) {
        casper.thenOpen(url + '#' + ctest, function() {
            test.assertNotEquals(this.evaluate(suite.sanitizer), '', ctest);
        });
    });

    casper.run(function() {
        test.done();
    });
});

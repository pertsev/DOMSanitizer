/* global casper */

var url = 'http:/localhost:9000/tmp/samples/page.html';

casper.test.begin('False Positive tests for JSLoose', function suite(test) {
    casper.start();

    var suite = require('specLoose/jsl.spec.js');
    suite.tests.forEach(function(ctest) {
        casper.thenOpen(url + '#' + ctest, function() {
            var res = this.evaluate(suite.sanitizer);
            if (typeof (res) === 'object') {
                test.assertNotEquals('', '', ctest + '\nError in: ' + ctest + '\nInjection type is: ' + res[0] + '\nInjection is: ' + res[1]);
            } else {
                test.assertNotEquals(res, '', ctest);
            }
        });
    });

    casper.run(function() {
        test.done();
    });
});

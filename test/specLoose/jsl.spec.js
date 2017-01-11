/* global DOMSanitizer */
/* eslint-disable no-script-url */
'use strict';

var tests = [
    'Division of Research on Learning in Formal and Informal Settings (DRL)',
    'jsessionid=FC030DBF5DDFA8AFA709EB25731DE4C0.w12',
    'mid=9&ep=7&du=www.autotrader.com',
    'stylus.export-japan.com',
    'rgb(51, 51, 51)',
    '=3ff=3d1=252F=2528a=255E2+cos=255E2=2528x=2529=252Bb=255E2+sin=255E2=2528x=2529=2529=26var=3d=26steps=3don',
    '6.2. Seria RH (SCARA)',
    '1%...dia',
    'search.php=3fquery=3dperl(ExtUtils=253A=253AEmbed)',
    '(S(vv51uyfmsek2rtmchje443a5))',
    'FOR=LLl2zLcqjlYJ.ouroLxIEXbkS.eEHuB1t3B1LX6xaSPH7dnuiULfpcHU;',
    'Find(\'ID\',\'49\')',
    'Ordinateur - Hybride (large)',
    'UN chief commends Tunisia\'s adoption of new constitution',
    'pET-26b(+)',
    '...php',
    '20110215-ASHFORD-FREESHIPPINGCOM-120x60 (2)',
    'ProjectM_Visualisation_Panel_(foo_uie_vis_projectM)',
    '&col_datesfma_col_datesfma_debut[date]=01',
    '13708086_Factor_VII_Morioka_(FVII_L-26P)_A_homozygous_missense_mutation_in_the_signal_sequence_identified_in_a_patient_with_factor_VII_deficiency',
    'f...r',
    '2016&col_datesfma_col_datesfma_fin[date]=31',
    'Products_GunTorch_GunsandTorches-Pro-Torch-PTA-26F(LincolnElectric)',
    'TSSC new leaflet 2013 3fold.pdf',
    'the-26s-proteasomal-atpases-structure-function-regulation-and-potential-for-cancer-therapies.pdf',
    'Open Diamond Bath Imaging Chamber for Oocyte Studies (RC-26Z)',
    'FOR=fAoPzWIqj1ZWJynZmVTWSf4mqIr47scA7usJ7vZSfSCpTzVw8c91.o0.t0yp;',
    '(((Price=range[250..40000]&(Type=[Road]&SubType=[Sport Touring]))&Service=[Showroom])&Make=[BMW])',
    'ff476896(v=3dvs.85).aspx',
    'index.php=3ftitle=3d=25D0=2590=25D1=2581=25D0=25B8=25D0=25BC=25D1=2596=25D0=25BB=25D1=258F=25D1=2586=25D1=2596=25D1=258F_(=25D1=2581=25D0=25BE=25D1=2586=25D1=2596=25D0=25BE=25D0=25BB=25D0=25BE=25D0=25B3=25D1=2596=25D1=258F)=26veaction=3dedit=26vesection=3d1',
    'AREA=GOOTOP.GOO',
    'how-to-export-large-dataset-around-40k-rows-and-26columns-to-be-written-in-ex',
    'www.export.gov',
    'event=bea.portal.framework.internal.refresh&sID=1089877360442&pageid=Utilities&site=www.arrestocardiaco.com',
    'french-connections&ld=20120520&ap=3&app=1&c=info.dogpl&coi=1494&npp=10&p=0&pp=0&mid=9&ep=10&du=edsitement.neh.gov',
    'Vendor_Profile_Form_(SP-26NB).pdf'
];

var sanitizer = function() {
    var dirty = location.hash.substring(1);
    return DOMSanitizer.sanitize(dirty, {CONTEXTS: ['jsLoose']});
};

module.exports = {tests: tests, sanitizer: sanitizer};

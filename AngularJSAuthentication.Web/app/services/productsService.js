'use strict';
app.factory('productsService', ['$http', 'ngAuthSettings', function ($http, ngAuthSettings) {

    var serviceBase = ngAuthSettings.apiServiceBaseUri;

    var ordersServiceFactory = {};

    var getProducts = function () {

        return $http.get(serviceBase + 'api/products').then(function (results) {
            return results;
        });
    };

    ordersServiceFactory.getProducts = getProducts;

    return ordersServiceFactory;

}]);
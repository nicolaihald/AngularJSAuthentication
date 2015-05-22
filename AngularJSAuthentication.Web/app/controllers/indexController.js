'use strict';
app.controller('indexController', ['$scope', '$location', 'authService', function ($scope, $location, authService) {

    $scope.logOut = function () {
        authService.logOut();
        $location.path('/home');
    }

    $scope.showImage = function(imageUrl) {
        return imageUrl != null && imageUrl.length > 0;
    }

    $scope.authentication = authService.authentication;

}]);
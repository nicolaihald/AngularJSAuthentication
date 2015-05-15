'use strict';
app.controller('associateController', ['$scope', '$location', '$timeout', 'authService', '$q', function ($scope, $location, $timeout, authService, $q) {

    $scope.savedSuccessfully = false;
    $scope.message = "";

    $scope.registerData = {
        userName: authService.externalAuthData.userName,
        provider: authService.externalAuthData.provider,
        externalAccessToken: authService.externalAuthData.externalAccessToken,
        state: authService.externalAuthData.state

    };

    $scope.registerExternal = function () {

        authService.registerExternal($scope.registerData).then(function (response) {

            $scope.savedSuccessfully = true;
            $scope.message = "User has been registered successfully, you will be redicted to orders page in 2 seconds.";
            startTimer();

        },
          function (response) {
              var errors = [];
              for (var key in response.modelState) {
                  errors.push(response.modelState[key]);
              }
              $scope.message = "Failed to register user due to:" + errors.join(' ');
          });
    };


    // NEW:
    $scope.registerExternalAndObtainAccessToken = function () {
        var obtainAccessTokenData = {
            userName: authService.externalAuthData.userName,
            provider: authService.externalAuthData.provider,
            external_access_token: authService.externalAuthData.externalAccessToken,
            state: authService.externalAuthData.state
        };


        function register() {
            var dfd = $q.defer();

            authService.registerExternal($scope.registerData).then(function (response) {

                $scope.savedSuccessfully = true;
                $scope.message = "User has been registered successfully, obtaining new access token. Please wait... ";
                //startTimer();
                dfd.resolve();

            },
            function (response) {
                var errors = [];
                for (var key in response.modelState) {
                    errors.push(response.modelState[key]);
                }

                if (response.message) {
                    errors.push(response.message);
                }

                $scope.message = "Failed to register user due to:" + errors.join(' ');
                dfd.reject($scope.message);
            });

            return dfd.promise;
        };

        function obtainToken() {
            var dfd = $q.defer();

            authService.obtainAccessToken(obtainAccessTokenData).then(function (response) {

                $scope.savedSuccessfully = true;
                $scope.message = "User has been registered successfully!";
                //startTimer();

                dfd.resolve();


            },
            function (response) {
                $scope.message = "Failed to obtain local access token due to: " + response;
                dfd.reject($scope.message);

            });

            return dfd.promise;
        };

        function redirect() {

            $scope.message = "Obtained token successfully, you will be redicted to orders page in 2 seconds.";
            startTimer();
        };


        register().then(function(registerResult) {
            console.log('register done', registerResult);
            //setTimeout(function () {
                console.log('now obtain token');
                obtainToken().then(redirect);
            //}, 4000);
        });

        console.log('registerExternalAndObtainAccessToken');


    };

    $scope.registerExternal = $scope.registerExternalAndObtainAccessToken;

    var startTimer = function () {
        var timer = $timeout(function () {
            $timeout.cancel(timer);
            $location.path('/orders');
        }, 2000);
    }

}]);
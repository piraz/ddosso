$(document).ready(function () {
    var location_root = document.location.pathname.replace("profile", "");

    ProfileModel = can.Model.extend({
        create : "POST " + location_root + "sign_in"
    },{});

    can.Component.extend({
        tag: "profileComponent",
        template: can.view("#profileComponentStache"),
        viewModel:{
            hasError: false,
            postContainerFocus: false,
            errorMessage: "",
            hasPasswordError: false,
            hasUsernameError: false,
            passwordError: "",
            usernameError: "",
            blurTimeout: null,
            signin: new ProfileModel(),
            processLogin: function(login) {
                console.debug(login);
                window.location = login.next_url;
            },
            processLoginError: function(response) {
                var errors = response.responseJSON.errors;
                var errorMessage = '';

            }
        },
        events: {
            "#signinButton click": function() {

            },
            "#signinForm submit": function(event) {
                return false;
            },
            "#signupLink click": function(event) {
                window.document.location = location_root + "sign_up";
            }
        }
    });

    $("#profileComponentHolder").html(
        can.stache("<profileComponent></profileComponent>")());
});

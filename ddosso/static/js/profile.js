$(document).ready(function () {
    var location_root = document.location.pathname.replace("profile", "");

    ProfileModel = can.Model.extend({
        findOne: "POST " + location_root + "profile/diaspora",
    },{});

    can.Component.extend({
        tag: "profileComponent",
        template: can.view("#profileComponentStache"),
        viewModel:{
            diaspora_url: "",
            profile: null,
            tags: [],
            signin: new ProfileModel(),
            updateProfile: function() {
                var viewModel = this;
                var values = {};
                values._xsrf = get_xsrf();
                ProfileModel.findOne(values, function (response) {
                    viewModel.attr("diaspora_url", response.diaspora_url);
                    viewModel.attr("profile", response.profile);
                    viewModel.attr("tags", response.tags);
                    console.debug(response);
                });
            }
        },
        events: {
            "inserted": function () {
                this.viewModel.updateProfile();
            }
        }
    });

    can.Component.extend({
        tag: "socialProfilesComponent",
        template: can.view("#socialProfilesComponentStache"),
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

    $("#socialProfilesComponentHolder").html(
        can.stache("<socialProfilesComponent></socialProfilesComponent>")());
});

$(document).ready(function () {
    SignupModel = can.Model({
        create : "POST " + document.location.pathname
    },{});

    can.Component.extend({
        tag: "sign-up-form",
        template: can.view("#sign_up_form"),
        viewModel:{
            error: false,
            postContainerFocus: false,
            errorMessage: "",
            hasEmailError: false,
            hasPasswordConfError: false,
            hasPasswordError: false,
            hasUsernameError: false,
            emailError: "",
            passwordError: "",
            passwordConfError: "",
            usernameError: "",
            blurTimeout: null,
            signup: new SignupModel(),
            blurControls: function() {
                var viewModel = this;
                var doBlur = function() {
                    viewModel.attr("postContainerFocus", false);
                }
                this.blurTimeout = window.setTimeout(doBlur, 100);
            },
            processLogin: function(login) {
                window.location = login.next_url;
            },
            processLoginError: function(response) {
                var errors = response.responseJSON.errors;
                var errorMessage = '';
                if(errors.hasOwnProperty('email')) {
                    this.viewModel.attr("hasEmailError", true);
                    this.viewModel.attr("emailError", errors.email);
                }
                if(errors.hasOwnProperty('password')) {
                    this.viewModel.attr("hasPasswordError", true);
                    this.viewModel.attr("passwordError", errors.password);
                }
                if(errors.hasOwnProperty('passwordConf')) {
                    this.viewModel.attr("hasPasswordConfError", true);
                    this.viewModel.attr("passwordConfError",
                        errors.passwordConf);
                }
                if(errors.hasOwnProperty('username')) {
                    this.viewModel.attr("hasUsernameError", true);
                    this.viewModel.attr("usernameError", errors.username);
                }
                var errors = new can.Map(response.responseJSON.errors);
                errors.each(
                    function(element, index, list) {
                        if(!this.viewModel.attr('error')){
                            this.viewModel.attr('error', true);
                        }
                        errorMessage += element[0] + '<br>';
                    }.bind(this)
                );
                this.viewModel.attr('errorMessage', errorMessage);
            }
        },
        events: {
            "#login_button click": function() {
                //this.viewModel.attr('error', false);
                //this.viewModel.attr('errorMessage', '');
                this.viewModel.attr("hasEmailError", false);
                this.viewModel.attr("hasPasswordError", false);
                this.viewModel.attr("hasPasswordConfError", false);
                this.viewModel.attr("hasUsernameError", false);
                this.viewModel.attr('emailError', "");
                this.viewModel.attr('passwordError', "");
                this.viewModel.attr('passwordConfError', "");
                this.viewModel.attr("usernameError", "");
                var form = this.element.find('form');
                var values = can.deparam(form.serialize());
                var parameters = [];
                values._xsrf = getCookie('_xsrf');
                console.debug(values);
                this.viewModel.signup.attr(values).save(
                    this.viewModel.processLogin.bind(this),
                    this.viewModel.processLoginError.bind(this)
                );
            },
            "#login_form submit": function(event) {
                return false;
            }
        }
    });
    $("#ddosso_sign_up_form").html(can.stache("<sign-up-form></sign-up-form>")());
});

package server

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/dex/user"
	"github.com/coreos/go-oidc/oidc"
)

const (
	maxNameLength  = 50
	maxEmailLength = 254
)

var (
	ErrorInvalidFirstName = formError{
		Field: "fname",
		Error: "Please enter a valid first name ",
	}
	ErrorInvalidLastName = formError{
		Field: "lname",
		Error: "Please enter a valid last name",
	}
	ErrorInvalidCompany = formError{
		Field: "company",
		Error: "Please enter a valid company name",
	}
	ErrorDuplicateCompanyName = formError{
		Field: "company",
		Error: "The company name is already in use; please choose another.",
	}
	ErrorInvalidEmail = formError{
		Field: "email",
		Error: "Please enter a valid email",
	}
	ErrorDuplicateEmail = formError{
		Field: "email",
		Error: "The email is already in use; please choose another.",
	}
	ErrorInvalidPassword = formError{
		Field: "password",
		Error: "Please enter a valid password",
	}
	ErrorNoConfirmPassword = formError{
		Field: "confirm-password",
		Error: "Required",
	}
	ErrorPasswordNotMatch = formError{
		Field: "password-match",
		Error: "The passwords you entered are not matched. Please enter again.",
	}
	ErrorTermsNotAccepted = formError{
		Field: "terms",
		Error: "Please accept the Terms of Service below in order to create an account",
	}
)

type createAccountTemplateData struct {
	Error      bool
	FormErrors []formError
	Message    string
	FirstName  string
	LastName   string
	Company    string
	Email      string
	Code       string
}

func (d createAccountTemplateData) FieldError(fieldName string) *formError {
	for _, e := range d.FormErrors {
		if e.Field == fieldName {
			return &e
		}
	}
	return nil
}

type emailConfirmationData struct {
	Error     bool
	Message   string
	FirstName string
	Email     string
	LoginURL  string
	Code      string
}

func handleCreateAccountFunc(s *Server, tpl Template) http.HandlerFunc {

	errPage := func(w http.ResponseWriter, msg string, code string, status int) {
		data := createAccountTemplateData{
			Error:   true,
			Message: msg,
			Code:    code,
		}
		execTemplateWithStatus(w, tpl, data, status)
	}

	internalError := func(w http.ResponseWriter, err error) {
		log.Errorf("Internal Error during registration: %v", err)
		errPage(w, "There was a problem processing your request.", "", http.StatusInternalServerError)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			internalError(w, err)
			return
		}

		// verify the user has a valid code.
		key := r.Form.Get("code")
		sessionID, err := s.SessionManager.GetSessionByKey(key)
		if err != nil {
			w.Header().Set("Location", httpPathError)
			w.WriteHeader(http.StatusFound)
			return
		}

		ses, err := s.SessionManager.Get(sessionID)
		if err != nil || ses == nil {
			return
		}

		validate := r.Form.Get("validate") == "1"
		formErrors := []formError{}

		firstName := strings.TrimSpace(r.Form.Get("fname"))
		lastName := strings.TrimSpace(r.Form.Get("lname"))
		company := strings.TrimSpace(r.Form.Get("company"))
		email := strings.TrimSpace(r.Form.Get("email"))
		password := r.Form.Get("password")
		confirmPassword := r.Form.Get("confirm-password")
		terms := r.Form.Get("terms")

		if validate {
			if firstName == "" || len(firstName) > maxNameLength {
				formErrors = append(formErrors, ErrorInvalidFirstName)
			}
			if lastName == "" || len(lastName) > maxNameLength {
				formErrors = append(formErrors, ErrorInvalidLastName)
			}
			if company == "" || len(company) > maxNameLength {
				formErrors = append(formErrors, ErrorInvalidCompany)
			}
			if email == "" || len(email) > maxEmailLength || !user.ValidEmail(email) {
				formErrors = append(formErrors, ErrorInvalidEmail)
			}
			if password == "" {
				formErrors = append(formErrors, ErrorInvalidPassword)
			}
			if confirmPassword == "" {
				formErrors = append(formErrors, ErrorNoConfirmPassword)
			}
			if password != "" && confirmPassword != "" && password != confirmPassword {
				formErrors = append(formErrors, ErrorPasswordNotMatch)
			}
			if terms != "on" {
				formErrors = append(formErrors, ErrorTermsNotAccepted)
			}
		}

		data := createAccountTemplateData{
			Code:      key,
			FirstName: firstName,
			LastName:  lastName,
			Company:   company,
			Email:     email,
		}

		if len(formErrors) > 0 || !validate {
			data.FormErrors = formErrors
			if !validate {
				execTemplate(w, tpl, data)
			} else {
				execTemplateWithStatus(w, tpl, data, http.StatusBadRequest)
			}
			return
		}

		userID, err := s.UserManager.RegisterUserAndOrganization(firstName, lastName, company, email, password, ses.ConnectorID)

		if err != nil {
			formErrors := errToFormErrors(err)
			if len(formErrors) > 0 {
				data.FormErrors = formErrors
				execTemplate(w, tpl, data)
				return
			}

			internalError(w, err)
			return
		}

		ses, err = s.SessionManager.AttachRemoteIdentity(sessionID, oidc.Identity{
			ID: userID,
		})
		if err != nil {
			internalError(w, err)
			return
		}

		ses, err = s.SessionManager.AttachUser(sessionID, userID)
		if err != nil {
			internalError(w, err)
			return
		}

		// Kill old session key and create a new code for resending account confirmation
		if _, err := s.SessionManager.ExchangeKey(key); err != nil {
			log.Errorf("Failed killing sessionKey %q: %v", key, err)
		}
		code, err := s.SessionManager.NewSessionKey(sessionID)
		if err != nil {
			internalError(w, err)
			return
		}

		q := url.Values{}
		q.Set("code", code)
		accountConfirmURL := path.Join(s.IssuerURL.Path, httpPathSendAccountConfirm) + "?" + q.Encode()
		w.Header().Set("Location", accountConfirmURL)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
}

func handleSendAccountConfirmationFunc(s *Server, tpl Template) http.HandlerFunc {

	errPage := func(w http.ResponseWriter, msg, code, loginURL string, status int) {
		data := emailConfirmationData{
			Error:    true,
			Message:  msg,
			Code:     code,
			LoginURL: loginURL,
		}
		execTemplateWithStatus(w, tpl, data, status)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, err)
			return
		}

		loginURL := r.Form.Get("login_url")

		// verify the user has a valid code.
		key := r.Form.Get("code")
		sessionID, err := s.SessionManager.GetSessionByKey(key)
		if err != nil {
			w.Header().Set("Location", httpPathError)
			w.WriteHeader(http.StatusFound)
			return
		}

		ses, err := s.SessionManager.Get(sessionID)
		if err != nil || ses == nil {
			return
		}

		loginURL = s.AccountHomeURL.String()
		usr, err := s.UserRepo.Get(nil, ses.UserID)
		if err != nil {
			log.Errorf("Error getting user: %v", err)
			errPage(w, "There was a problem processing your request.", key, loginURL, http.StatusInternalServerError)
			return
		}
		_, err = s.UserEmailer.SendEmailVerification(usr.ID, ses.ClientID, ses.RedirectURL)
		if err != nil {
			log.Errorf("Error sending email verification: %v", err)
			errPage(w, "There was a problem processing your request.", key, loginURL, http.StatusInternalServerError)
			return
		}

		execTemplate(w, tpl, emailConfirmationData{
			FirstName: usr.FirstName,
			Email:     usr.Email,
			LoginURL:  loginURL,
			Code:      key,
		})
	}
}

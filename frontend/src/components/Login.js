import React, { useState, useEffect, useCallback } from 'react';
import { validateField } from '../utils/constants.js';

const minInputLength = 4;
const validationConfig = {
  email: {
    required: (value) => value === '',
    minLength: (value) => value.length < minInputLength
  },
  password: {
    required: (value) => value === '',
    email: (value) => /^.+@\w+\.\w{2,3}/gm.test(value)
  }
}

function Login({ handleLogin, onRender }) {
  const [isDisabled, setIsDisabled] = useState(true);
  const [formValues, setFormValues] = useState({
    email: '',
    password: ''
  });
  const [errors, setErrors] = useState({
    email: {
      required: true,
      email: true
    },
    password: {
      required: true,
      minLength: true
    }
  });
  const { email, password } = formValues;
  const isEmailInvalid = Object.values(errors.email).some(Boolean);
  const isPasswordInvalid = Object.values(errors.password).some(Boolean);
  const isSubmitDisabled = isPasswordInvalid || isEmailInvalid;
  const isEmailValid = errors.email.required || errors.email.email;
  const isPasswordValid = errors.password.required || errors.password.minLength;
  const isInactive = isDisabled || isSubmitDisabled || onRender;
  
  function handleSubmit(event) {
    event.preventDefault();
    handleLogin(formValues.email, formValues.password);
    setIsDisabled(true);
  };

  const handleInputChange = useCallback((event) => {
      setIsDisabled(false);
      const {name, value} = event.target;
      setFormValues((state) => ({ ...state, [name]: value }));
  }, [setFormValues]);

  useEffect(
    function validateInputs() {
      const { email, password } = formValues;
      const passwordValidation = validateField(validationConfig.password, password);
      const emailValidation = validateField(validationConfig.email, email);
      setErrors({
        email: emailValidation,
        password: passwordValidation
      });
    }, [formValues, setErrors]
  );

  useEffect(() => {
    setIsDisabled(true);
    return () => {
      setFormValues({
        email: '',
        password: ''
      });
    };
  }, []);

  return (
    <section className="login">
      <div className="login__container">
        <h2 className="login__title">Вход</h2>
        <form name="login" className="form-login" onSubmit={handleSubmit} noValidate>
          <fieldset className="form-login__fieldset">
            <label className="form__field">
              <input
                className={`form__input form__input_position_sign ${isDisabled ? '' : isEmailInvalid}`}
                type="email"
                id="login-email"
                name="email"
                placeholder="Email"
                required
                value={email}
                onChange={handleInputChange}
              />
              <span className={`form__error ${isDisabled ? '' : isEmailInvalid && 'form__error_active'}`}>{isEmailValid ? errors.email.required
                ? 'Обязательное поле'
                : 'Введите email'
              : ''}</span>
            </label>
            <label className="form__field">
              <input
                className={`form__input form__input_position_sign ${isDisabled ? '' : isPasswordInvalid}`}
                type="password"
                id="login-password"
                name="password"
                placeholder="Пароль"
                minLength={minInputLength}
                required
                value={password}
                onChange={handleInputChange}
              />
              <span className={`form__error ${isDisabled ? '' : isPasswordInvalid && 'form__error_active'}`}>{isPasswordValid ? errors.password.required
                ? 'Обязательное поле'
                : `Введите пароль из не менее ${minInputLength} символов`
              : ''}</span>
            </label>
          </fieldset>
          <button
            type="submit"
            className={`form__btn form__btn_position_sign ${isInactive && 'form__btn_disabled'}`}
            disabled={isInactive}
          >{onRender ? 'Авторизация...' : 'Войти'}</button>
        </form>
        <p className="login__auth-text">&nbsp;</p>
      </div>
    </section>
  )
}

export default Login;
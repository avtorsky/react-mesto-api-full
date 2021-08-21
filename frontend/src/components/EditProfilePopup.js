import React, { useEffect, useContext } from 'react';
import PopupWithForm from './PopupWithForm.js';
import { CurrentUserContext } from '../contexts/CurrentUserContext.js';
import { formInputClass } from '../utils/constants.js';
import { useFormValidation } from '../hooks/useFormValidation.js';

function EditProfilePopup({ isOpen, onClose, onUpdateUser, onRender }) {
  const currentUser = useContext(CurrentUserContext);
  const { values, handleChange, errors, isValid, resetForm } = useFormValidation()

  function handleSubmit(event) {
    event.preventDefault();
    onUpdateUser({
      name: values.name,
      about: values.status
    });
  };

  useEffect(() => {
    resetForm();
    if (isOpen) {
      resetForm({ name: currentUser.name, status: currentUser.about }, {}, true);
    };
  }, [currentUser, isOpen, resetForm]);

  return (
    <PopupWithForm
      name="edit"
      title="Редактировать профиль"
      submitButtonText={onRender ? "Сохранение..." : "Сохранить"}
      isOpen={isOpen}
      onClose={onClose}
      onSubmit={handleSubmit}
      submitDisabled={!isValid}
    >
      <fieldset className="form-edit__fieldset">
        <label className="form__field">
          <input
            className={`form__input form-edit__input ${errors.name ? formInputClass.inputErrorClass : ""}`}
            type="text"
            id="profile-name"
            name="name"
            placeholder="Имя пользователя"
            minLength="2"
            maxLength="40"
            required
            value={values.name || ""}
            onChange={handleChange}
          />
          <span className={`form__input-error ${formInputClass.errorClass}`} id="profile-name-error">{errors.name || ""}</span>
        </label>
        <label className="form__field">
          <input
            className={`form__input form-edit__input ${errors.status ? formInputClass.inputErrorClass : ""}`}
            type="text"
            id="profile-status"
            name="status"
            placeholder="Статус"
            minLength="2"
            maxLength="200"
            required
            value={values.status || ""}
            onChange={handleChange}
          />
          <span className={`form__input-error ${formInputClass.errorClass}`} id="profile-status-error">{errors.status || ""}</span>
        </label>
      </fieldset>
    </PopupWithForm>
  );
};

export default EditProfilePopup;
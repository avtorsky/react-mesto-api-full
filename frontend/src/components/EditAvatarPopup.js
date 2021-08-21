import React, { useContext, useEffect } from 'react';
import PopupWithForm from './PopupWithForm.js';
import { CurrentUserContext } from '../contexts/CurrentUserContext.js';
import { formInputClass } from '../utils/constants.js';
import { useFormValidation } from '../hooks/useFormValidation.js';

function EditAvatarPopup({ isOpen, onClose, onUpdateAvatar, onRender }) {
  const currentUser = useContext(CurrentUserContext);
  const { values, handleChange, errors, isValid, resetForm } = useFormValidation()
  
  function handleSubmit(event) {
    event.preventDefault();
    onUpdateAvatar({
      avatar: values.link
    });
  };

  useEffect(() => {
    if (isOpen) {
      resetForm({ avatar: currentUser.avatar }, {}, false)
    } else {
      resetForm();
    };
  }, [isOpen, currentUser, resetForm]);

  return (
    <PopupWithForm
      name="avatar-edit"
      title="Новый аватар"
      submitButtonText={onRender ? "Сохранение..." : "Сохранить"}
      isOpen={isOpen}
      onClose={onClose}
      onSubmit={handleSubmit}
      submitDisabled={!isValid}
    >
      <fieldset className="form-avatar-edit__fieldset">
        <label className="form__field">
          <input
            className={`form__input form-avatar-edit__input ${errors.link ? formInputClass.inputErrorClass : ""}`}
            type="url"
            id="avatar-link"
            name="link"
            placeholder="Ссылка на аватар"
            required
            // ref={avatarLink}
            onChange={handleChange}
            pattern="https?://.+"
          />
          <span
            className={`form__input-error ${formInputClass.errorClass}`}
            id="avatar-link-error"
          >{errors.link || ""}</span>
        </label>
      </fieldset>
    </PopupWithForm>
  );
};

export default EditAvatarPopup;
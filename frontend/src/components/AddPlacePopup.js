import React, { useEffect } from 'react';
import PopupWithForm from './PopupWithForm.js';
import { formInputClass } from '../utils/constants.js';
import { useFormValidation } from '../hooks/useFormValidation.js';

function AddPlacePopup({ isOpen, onClose, onAddCard, onRender }) {
  const { values, handleChange, errors, isValid, resetForm } = useFormValidation()

  function handleSubmit(event) {
    event.preventDefault();
    onAddCard(values);
  };

  useEffect(() => {
    resetForm();
  }, [isOpen, resetForm]);

  return (
    <PopupWithForm
      name="add"
      title="Новая фотокарточка"
      submitButtonText={onRender ? "Сохранение..." : "Сохранить"}
      isOpen={isOpen}
      onClose={onClose}
      onSubmit={handleSubmit}
      submitDisabled={!isValid}
    >
      <fieldset className="form-add__fieldset">
        <label className="form__field">
          <input
            className={`form__input form-add__input ${errors.name ? formInputClass.inputErrorClass : ""}`}
            type="text"
            id="card-name"
            name="name"
            placeholder="Название карточки"
            minLength="2"
            maxLength="30"
            required
            value={values.name || ""}
            onChange={handleChange}
          />
          <span className={`form__input-error ${formInputClass.errorClass}`} id="card-name-error">{errors.name || ""}</span>
        </label>
        <label className="form__field">
          <input
            className={`form__input form-add__input ${errors.link ? formInputClass.inputErrorClass : ""}`}
            type="url"
            id="card-link"
            name="link"
            placeholder="Ссылка на фотографию"
            required
            value={values.link || ""}
            onChange={handleChange}
            pattern="https?://.+"
          />
          <span className={`form__input-error ${formInputClass.errorClass}`} id="card-link-error">{errors.link || ""}</span>
        </label>
      </fieldset>
    </PopupWithForm>
  );
};

export default AddPlacePopup;
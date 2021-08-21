import React, { useEffect } from 'react';

function PopupWithForm({ name, isOpen, onClose, title, children, submitButtonText, onSubmit, submitDisabled }) {
  const keyEscapeSelector = 'Escape';

  function handleEventClose() {
    onClose();
  };

  function handleOverlayClose(event) {
    if (event.target === event.currentTarget) {
      handleEventClose();
    }
  };

  useEffect(() => {
    function handleEscClose(event) {
      if (event.key === keyEscapeSelector) {
        handleEventClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscClose);
    } else {
      document.removeEventListener('keydown', handleEscClose);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  return (
    <section className={`popup popup-${name} ${isOpen && "popup_active"}`} onClick={handleOverlayClose}>
      <div className={`popup-${name}__window`}>
        <button className={`popup__close popup-${name}__close-btn`} type="button" onClick={handleEventClose}></button>
        <form className={`form form-${name}`} name={name} onSubmit={onSubmit} noValidate>
          <h2 className={`form-${name}__title`}>{title}</h2>
          {children}
          <button className={`form__btn form-${name}__save-btn`} type="submit" disabled={submitDisabled}>{submitButtonText}</button>
        </form>
      </div>
    </section >
  );
};

export default PopupWithForm;
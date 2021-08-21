import React from 'react';
import { useHistory } from 'react-router-dom';
import regSuccess from '../images/infotooltip/registration-success.svg';
import regError from '../images/infotooltip/registration-error.svg';

function InfoTooltip({ isOpen, onClose, onRegister, registration }) {
  let history = useHistory();
  
  function handleOverlayClose(event) {
    if (event.target === event.currentTarget) {
      onClose();
    }
  };

  return (
    <section className={`popup popup-tooltip ${isOpen && "popup_active"}`} onClick={handleOverlayClose}>
      <div className="popup-tooltip__window">
        <button
          onClick={() => {
            onClose();
            registration && history.push('/sign-in');
            onRegister(false);
          }}
          type="button"
          className="popup__close popup-tooltip__close-btn"
        />
        <img
          className="popup-tooltip__image"
          src={ registration ? regSuccess : regError }
          alt="Статус регистрации"
        />
        <h2 className="popup-tooltip__title">
          {registration ? 'Вы успешно зарегистрировались!' : 'Что-то пошло не так. Попробуйте ещё раз.'}
        </h2>
      </div>
    </section>
  )
}

export default InfoTooltip;
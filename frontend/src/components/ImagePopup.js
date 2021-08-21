import React, { useEffect } from 'react';

function ImagePopup({ card, isOpen, onClose }) {
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
    <section className={`popup popup-open ${card && isOpen ? "popup_active" : ''}`} onClick={handleOverlayClose}>
      <div className="popup-open__window">
        <button className="popup__close popup-open__close-btn" type="button" onClick={handleEventClose}></button>
        <figure className="popup-open__figure">
          <img src={card.link} alt={card.name} className="popup-open__image" />
          <figcaption className="popup-open__figcaption">{card.name}</figcaption>
        </figure>
      </div>
    </section>
  );
};

export default ImagePopup;
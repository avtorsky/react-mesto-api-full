import React from 'react';
import PopupWithForm from './PopupWithForm.js';

function DeleteCardPopup({ isOpen, onClose, card, onDeleteCard, onRender }) {
  function handleSubmit(event) {
    event.preventDefault();
    onDeleteCard(card);
  };

  return (
    <PopupWithForm
      name="delete"
      title="Удалить фотокарточку?"
      isOpen={isOpen}
      onClose={onClose}
      submitButtonText={onRender ? "Удаление..." : "Да"}
      onSubmit={handleSubmit}
    />
  );
};

export default DeleteCardPopup;
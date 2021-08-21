import React, { useContext } from 'react';
import { CurrentUserContext } from '../contexts/CurrentUserContext.js';

function Card({ card, cardOpen, onLikeCard, onDeleteCard }) {
  const currentUser = useContext(CurrentUserContext);
  const isOwn = card.owner._id === currentUser._id;
  const cardDeleteButtonClassName = (
    `element__delete-btn ${isOwn ? 'element__delete-btn_active' : 'element__delete-btn'}`
  );
  const isLiked = card.likes.some(cardLike => cardLike._id === currentUser._id);
  const cardLikeButtonClassName = (
    `element__like-btn ${isLiked && `element__like-btn_active`}`
  );

  function handleCardClick() {
    cardOpen(card);
  };

  function handleLikeClick() {
    onLikeCard(card);
  };

  function handleDeleteClick() {
    onDeleteCard(card);
  };

  return (
    <div className="element">
      <div className={cardDeleteButtonClassName} onClick={handleDeleteClick}></div>
      <img src={card.link} alt={`${card.name} by ${card.owner.name}`} className="element__photo" onClick={handleCardClick} />
      <div className="element__label">
        <h2 className="element__name">{card.name}</h2>
        <div className="element__like-container">
          <button className={cardLikeButtonClassName} onClick={handleLikeClick}></button>
          <span className="element__like-count">{card.likes.length}</span>
        </div>
      </div>
    </div>
  );
};

export default Card;
import React, { useContext } from 'react';
import Card from './Card.js';
import { CurrentUserContext } from '../contexts/CurrentUserContext.js';

function Main({ onEditAvatar, onEditProfile, onAddCard, onClickCard, cards, onLikeCard, onDeleteCard }) {
  const currentUser = useContext(CurrentUserContext);

  return (
    <main className="content">
      <section className="profile">
        <img src={currentUser.avatar} alt="Аватар пользователя" className="profile__avatar" />
        <div className="profile__avatar-edit-btn" onClick={onEditAvatar}></div>
        <div className="profile__info">
          <h1 className="profile__name">{currentUser.name}</h1>
          <button className="profile__edit-btn" aria-label="Редактировать профиль" type="button" onClick={onEditProfile}></button>
          <p className="profile__status">{currentUser.about}</p>
        </div>
        <button className="profile__add-btn" aria-label="Добавить фотокарточку" type="button" onClick={onAddCard}></button>
      </section>
      <section className="elements">
        {cards.map((card) => (
          <Card
            card={card}
            key={card._id}
            cardOpen={onClickCard}
            onLikeCard={onLikeCard}
            onDeleteCard={onDeleteCard}
          />
        ))}
      </section>
    </main>
  )
};

export default Main;
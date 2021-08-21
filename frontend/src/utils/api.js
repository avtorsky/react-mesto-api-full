class Api {
  constructor(options) {
    this.baseUrl = options.baseUrl;
    this.headers = options.headers;
  };

  _handleResponse(res) {
    if (res.ok) {
      return res.json();
    } else {
      console.log(`Ошибка: ${res.status}`);
      return Promise.reject(res.statusText);
    }
  };

  getUserInfo() {
    return fetch(`${this.baseUrl}/users/me`, {
      method: 'GET',
      headers: this.headers
    })
      .then(this._handleResponse);
  };

  setUserInfo(name, status) {
    return fetch(`${this.baseUrl}/users/me`, {
      method: 'PATCH',
      headers: this.headers,
      body: JSON.stringify({
        name: name,
        about: status,
      })
    })
      .then(this._handleResponse);
  };

  setUserAvatar(link) {
    return fetch(`${this.baseUrl}/users/me/avatar`, {
      method: 'PATCH',
      headers: this.headers,
      body: JSON.stringify({
        avatar: link
      })
    })
      .then(this._handleResponse);
  };

  getInitialCards() {
    return fetch(`${this.baseUrl}/cards`, {
      method: 'GET',
      headers: this.headers
    })
      .then(this._handleResponse);
  };

  addCard(name, link) {
    return fetch(`${this.baseUrl}/cards`, {
      method: 'POST',
      headers: this.headers,
      body: JSON.stringify({
        name: name,
        link: link
      })
    })
      .then(this._handleResponse);
  };

  deleteCard(cardId) {
    return fetch(`${this.baseUrl}/cards/${cardId}`, {
      method: 'DELETE',
      headers: this.headers
    })
      .then(this._handleResponse);
  };

  changeLikeCardStatus(cardId, setLike) {
    return fetch(`${this.baseUrl}/cards/likes/${cardId}`, {
      method: setLike ? 'PUT' : 'DELETE',
      headers: this.headers
    })
      .then(this._handleResponse);
  };

  getInitialData() {
    return Promise.all([this.getUserInfo(), this.getInitialCards()])
  };
};

const api = new Api({
  baseUrl: 'https://mesto.nomoreparties.co/v1/cohort-24',
  headers: {
    authorization: '159b35a8-d58e-44ce-a10d-31006f74b905',
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  }
});

export default api;
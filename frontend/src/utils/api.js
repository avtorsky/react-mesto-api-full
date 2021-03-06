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
      headers: this.headers,
      credentials: 'include',
    })
      .then(this._handleResponse);
  };

  setUserInfo(name, status) {
    return fetch(`${this.baseUrl}/users/me`, {
      method: 'PATCH',
      headers: this.headers,
      credentials: 'include',
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
      credentials: 'include',
      body: JSON.stringify({
        avatar: link
      })
    })
      .then(this._handleResponse);
  };

  getInitialCards() {
    return fetch(`${this.baseUrl}/cards`, {
      method: 'GET',
      headers: this.headers,
      credentials: 'include',
    })
      .then(this._handleResponse);
  };

  addCard(name, link) {
    return fetch(`${this.baseUrl}/cards`, {
      method: 'POST',
      headers: this.headers,
      credentials: 'include',
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
      headers: this.headers,
      credentials: 'include',
    })
      .then(this._handleResponse);
  };

  changeLikeCardStatus(cardId, setLike) {
    return fetch(`${this.baseUrl}/cards/${cardId}/likes`, {
      method: setLike ? 'PUT' : 'DELETE',
      headers: this.headers,
      credentials: 'include',
    })
      .then(this._handleResponse);
  };

  getInitialData() {
    return Promise.all([this.getUserInfo(), this.getInitialCards()])
  };
};

const api = new Api({
  baseUrl: 'https://api.mesto.avtorskydeployed.online',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

export default api;
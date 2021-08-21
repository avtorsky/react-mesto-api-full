import React from 'react';
import logo from '../images/header/header-logo.svg';
import { Link, Route, Switch, useHistory } from 'react-router-dom';

function Header({ email, onSignOut }) {
  let history = useHistory();

  function handleClick() {
    history.push('/');
  };

  return (
    <header className="header">
      <img src={logo} className="header__logo" alt="На главную - Mesto Russia" onClick={handleClick}/>
      <>
      <Switch>
        <Route path="/sign-in">
          <Link to="/sign-up" className="header__element">
            Регистрация
          </Link>
        </Route>
        <Route path="/sign-up">
          <Link to="/sign-in" className="header__element">
            Войти
          </Link>
        </Route>
        <Route path="/" exact>
          <>
            <nav className="header__menu">
              <p className="header__menu-element">{email}</p>
              <button
                onClick={onSignOut}
                className="header__menu-element header__menu-element_btn"
              >Выйти</button>
            </nav>
          </>
        </Route>
      </Switch>
      </>
    </header>
  );
};

export default Header;
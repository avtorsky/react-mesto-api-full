import React from 'react';

function NavMenu({ email, onSignOut}) {
  return (
    <div className="navmenu">
      <ul className="navmenu__content">
        <li className="navmenu__item">
          <p className="navmenu__element">{email}</p>
        </li>
        <li className="navmenu__item">
          <button
            onClick={onSignOut}
            className="navmenu__element navmenu__element_btn"
          >Выйти</button>
        </li>
      </ul>
    </div>
  );

};

export default NavMenu;
/* pages/login.js - #/login: username/password sign-in. */
import { api } from '../api.js';
import { startSession } from '../state.js';
import { h, field, btn, banner, withBusy, rules } from '../ui.js';

export default async function login(root) {
  const form = { username: '', password: '' };
  const msg = h('div', { class: 'form-msg' });
  const submit = btn('Sign in', null, { variant: 'primary', type: 'submit' });
  const el = h('form', {
    class: 'card narrow', novalidate: true,
    async onsubmit(e) {
      e.preventDefault();
      msg.replaceChildren();
      if (!form.username || !form.password) return msg.append(banner('error', 'Enter your username and password.'));
      await withBusy(submit, async () => {
        try {
          await startSession(await api.post('/auth/login', form, { quiet401: true }));
          location.hash = '#/';
        } catch (err) {
          msg.append(banner('error', err.status === 401 ? 'Wrong username or password.' : err.message));
        }
      });
    },
  }, [
    h('h1', 'Sign in'),
    field(form, 'username', { label: 'Username', required: true, autocomplete: 'username', validate: rules.len(1, 64) }),
    field(form, 'password', { label: 'Password', type: 'password', required: true, autocomplete: 'current-password' }),
    msg,
    h('div', { class: 'actions' }, submit),
  ]);
  root.append(el);
  el.querySelector('input').focus();
}

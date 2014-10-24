/**
 * Copyright (c) 2000-2013 Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

package com.liferay.portal.action;

import com.liferay.portal.kernel.portlet.WindowStateFactory;
import com.liferay.portal.kernel.util.CharPool;
import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.PropsKeys;
import com.liferay.portal.kernel.util.StringBundler;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.StringUtil;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.theme.ThemeDisplay;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.PortletKeys;
import com.liferay.portal.util.PrefsPropsUtil;
import com.liferay.portal.util.PropsValues;
import com.liferay.portal.util.WebKeys;
import com.liferay.portlet.PortletURLFactoryUtil;
import com.liferay.portlet.login.util.LoginUtil;

import javax.portlet.PortletMode;
import javax.portlet.PortletRequest;
import javax.portlet.PortletURL;
import javax.portlet.WindowState;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.struts.action.Action;
import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;

/**
 * @author Brian Wing Shun Chan
 * @author Scott Lee
 */
public class LoginAction extends Action {
	
	private static final Log _log = LogFactoryUtil.getLog(LoginAction.class);

	@Override
	public ActionForward execute(
			ActionMapping actionMapping, ActionForm actionForm,
			HttpServletRequest request, HttpServletResponse response)
		throws Exception {
			
		_log.debug("ActionForward::execute");

		ThemeDisplay themeDisplay = (ThemeDisplay)request.getAttribute(
			WebKeys.THEME_DISPLAY);
			
		_log.debug("AUTH_LOGIN_DISABLED: " + PropsValues.AUTH_LOGIN_DISABLED);

		if (PropsValues.AUTH_LOGIN_DISABLED) {
			String redirect = themeDisplay.getPathMain() + PropsValues.AUTH_LOGIN_DISABLED_PATH);
			
			_log.debug("redirect to: " + redirect);

			response.sendRedirect(redirect);

			return null;
		}

		if (PropsValues.COMPANY_SECURITY_AUTH_REQUIRES_HTTPS &&
			!request.isSecure()) {
				
			_log.debug("HTTPS required but request is !isSecure");

			StringBundler sb = new StringBundler(4);

			sb.append(PortalUtil.getPortalURL(request, true));
			sb.append(request.getRequestURI());
			sb.append(StringPool.QUESTION);
			sb.append(request.getQueryString());
			
			String redirect = sb.toString();
			_log.debug("redirect to: " + redirect);

			response.sendRedirect(redirect);

			return null;
		}

		String login = ParamUtil.getString(request, "login");
		String password = request.getParameter("password");
		boolean rememberMe = ParamUtil.getBoolean(request, "rememberMe");
		_log.debug("rememberMe: " + rememberMe);
		String authType = ParamUtil.getString(request, "authType");
		_log.debug("authType: " + authType);

		if (Validator.isNotNull(login) && Validator.isNotNull(password)) {
			_log.debug("login and password issued do LoginUtil.login");
			LoginUtil.login(
				request, response, login, password, rememberMe, authType);
		}

		HttpSession session = request.getSession();

		if ((session.getAttribute("j_username") != null) &&
			(session.getAttribute("j_password") != null)) {
			_log.debug("j_username and j_password are in session");

			if (PropsValues.PORTAL_JAAS_ENABLE) {
				_log.debug("return findForward to /portal/touch_protected.jsp");
				return actionMapping.findForward("/portal/touch_protected.jsp");
			}

			String redirect = ParamUtil.getString(request, "redirect");
			_log.debug("redirect query string param:" + redirect);

			redirect = PortalUtil.escapeRedirect(redirect);
			_log.debug("escape redirect query string param:" + redirect);

			if (Validator.isNull(redirect)) {
				_log.debug("redirect is null");
				redirect = themeDisplay.getPathMain();
				_log.debug("themeDisplay.getPathMain: " + redirect);
			}

			if (redirect.charAt(0) == CharPool.SLASH) {
				_log.debug("redirect start wiht slash");
				String portalURL = PortalUtil.getPortalURL(
					request, request.isSecure());
				_log.debug("portalURL: " + portalURL);

				if (Validator.isNotNull(portalURL)) {
					redirect = portalURL.concat(redirect);
					_log.debug("portalURL is not null concat with redirect: " + redirect);
				}
			}

			_log.debug("redirect to: " + redirect);
			response.sendRedirect(redirect);

			return null;
		}

		String redirect = PortalUtil.getSiteLoginURL(themeDisplay);
		_log.debug("getSiteLoginURL: " + redirect);

		if (Validator.isNull(redirect)) {
			_log.debug("getSiteLoginURL is null use AUTH_LOGIN_URL");
			redirect = PropsValues.AUTH_LOGIN_URL;
			_log.debug("AUTH_LOGIN_URL: " + AUTH_LOGIN_URL);
		}

		if (Validator.isNull(redirect)) {
			_log.debug("AUTH_LOGIN_URL is null do an URL with the an forced istance of login portlet");
			PortletURL portletURL = PortletURLFactoryUtil.create(
				request, PortletKeys.LOGIN, themeDisplay.getPlid(),
				PortletRequest.RENDER_PHASE);

			portletURL.setParameter("saveLastPath", Boolean.FALSE.toString());
			portletURL.setParameter("struts_action", "/login/login");
			portletURL.setPortletMode(PortletMode.VIEW);
			portletURL.setWindowState(getWindowState(request));

			redirect = portletURL.toString();
			_log.debug("portletURL: " + redirect);
		}

		if (PropsValues.COMPANY_SECURITY_AUTH_REQUIRES_HTTPS) {
			_log.debug("COMPANY_SECURITY_AUTH_REQUIRES_HTTPS true");
			String portalURL = PortalUtil.getPortalURL(request);
			String portalURLSecure = PortalUtil.getPortalURL(request, true);

			if (!portalURL.equals(portalURLSecure)) {
				redirect = StringUtil.replaceFirst(
					redirect, portalURL, portalURLSecure);
			}
			
			_log.debug("updated URL: " + redirect);
		}

		String loginRedirect = ParamUtil.getString(request, "redirect");
		_log.debug("redirect query string param:" + redirect);

		loginRedirect = PortalUtil.escapeRedirect(loginRedirect);
		_log.debug("escape redirect query string param:" + redirect);

		if (Validator.isNotNull(loginRedirect)) {
			_log.debug("redirect param is not null");
			if (PrefsPropsUtil.getBoolean(
					themeDisplay.getCompanyId(), PropsKeys.CAS_AUTH_ENABLED,
					PropsValues.CAS_AUTH_ENABLED)) {
				
				_log.debug("CAS enabled");
				redirect = loginRedirect;
				_log.debug("redirect query string param: " + loginRedirect);
			}
			else {
				_log.debug("CAS disabled");
				String loginPortletNamespace = PortalUtil.getPortletNamespace(
					PropsValues.AUTH_LOGIN_PORTLET_NAME);
				
				_log.debug("loginPortletNamespace: " + loginPortletNamespace);

				String loginRedirectParameter =
					loginPortletNamespace + "redirect";
					
				_log.debug("loginRedirectParameter: " + loginRedirectParameter);

				redirect = HttpUtil.setParameter(
					redirect, "p_p_id", PropsValues.AUTH_LOGIN_PORTLET_NAME);
				redirect = HttpUtil.setParameter(
					redirect, "p_p_lifecycle", "0");
				redirect = HttpUtil.setParameter(
					redirect, loginRedirectParameter, loginRedirect);
					
				_log.debug("updated URL: " + redirect);
			}
		}

		_log.debug("redirect to: " + redirect);
		response.sendRedirect(redirect);

		return null;
	}

	protected WindowState getWindowState(HttpServletRequest request) {
		WindowState windowState = WindowState.MAXIMIZED;

		String windowStateString = ParamUtil.getString(request, "windowState");

		if (Validator.isNotNull(windowStateString)) {
			windowState = WindowStateFactory.getWindowState(windowStateString);
		}

		return windowState;
	}

}
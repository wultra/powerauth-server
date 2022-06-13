<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<jsp:include page="header.jsp">
    <jsp:param name="pageTitle" value="PowerAuth Admin - New Callback URL"/>
</jsp:include>

<ol class="breadcrumb">
    <li><a class="black" href="${pageContext.request.contextPath}/application/list">Applications</a></li>
    <li><a class="black" href="${pageContext.request.contextPath}/application/detail/<c:out value="${applicationId}"/>#callbacks">Application Detail</a></li>
    <li class="active">New Callback</li>
</ol>

<div class="row">
    <div class="col-sm-7">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">New Callback</h3>
            </div>
            <div class="panel-body">
                <form class="form-horizontal" method="POST" action="${pageContext.request.contextPath}/application/detail/<c:out value="${applicationId}"/>/callback/create/do.submit">
                    <c:if test="${not empty error}">
                        <div class="form-group">
                            <div class="col-sm-9">
                                    <span style="color: #c0007f; margin-left: 10px;"><c:out value="${error}"/></span>
                            </div>
                        </div>
                    </c:if>
                    <div class="form-group">
                        <label for="name" class="col-sm-3 control-label">Callback Name</label>
                        <div class="col-sm-9">
                            <input type="text" id="name" name="name" class="form-control" value="${name}"/>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="callbackUrl" class="col-sm-3 control-label">Callback URL</label>
                        <div class="col-sm-9">
                            <input type="text" id="callbackUrl" name="callbackUrl" class="form-control" value="${callbackUrl}"/>
                        </div>
                    </div>
                    <div class="row">
                        <h4 class="panel-heading">Attributes</h4>
                    </div>
                    <div class="row">
                        <div class="col">
                            <label for="attr_activationId" class="col-sm-3 control-label">Activation ID</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_activationId" name="attr_activationId" checked disabled/>
                            </div>
                            <label for="attr_userId" class="col-sm-3 control-label">User ID</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_userId" name="attr_userId" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_userId}">checked</c:if>/>
                            </div>
                            <label for="attr_activationName" class="col-sm-3 control-label">Activation Name</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_activationName" name="attr_activationName" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_activationName}">checked</c:if>/>
                            </div>
                            <label for="attr_deviceInfo" class="col-sm-3 control-label">Device Info</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_deviceInfo" name="attr_deviceInfo" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_deviceInfo}">checked</c:if>/>
                            </div>
                            <label for="attr_platform" class="col-sm-3 control-label">Platform</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_platform" name="attr_platform" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_platform}">checked</c:if>/>
                            </div>
                            <label for="attr_activationFlags" class="col-sm-3 control-label">Activation Flags</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_activationFlags" name="attr_activationFlags" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_activationFlags}">checked</c:if>/>
                            </div>
                            <label for="attr_activationStatus" class="col-sm-3 control-label">Activation Status</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_activationStatus" name="attr_activationStatus" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_activationStatus}">checked</c:if>/>
                            </div>
                            <label for="attr_blockedReason" class="col-sm-3 control-label">Blocked Reason</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_blockedReason" name="attr_blockedReason" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_blockedReason}">checked</c:if>/>
                            </div>
                            <label for="attr_applicationId" class="col-sm-3 control-label">Application ID</label>
                            <div class="col-sm-1" style="margin-top: 6px">
                                <input type="checkbox" id="attr_applicationId" name="attr_applicationId" onchange="refreshActivationCallbackJson()" <c:if test="${not empty attr_applicationId}">checked</c:if>/>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <h4 class="panel-heading">Authentication</h4>
                    </div>
                    <div class="row">
                        <div class="col">
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">HTTP Basic
                                Authentication</label>
                                <div class="col-sm-8" style="margin-top: 6px">
                                    <input type="checkbox" id="auth_httpBasicEnabled" name="auth_httpBasicEnabled" <c:if test="${true eq auth_httpBasicEnabled}">checked</c:if>/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">HTTP Basic Username</label>
                                <div class="col-sm-4">
                                    <input type="text" id="auth_httpBasicUsername" name="auth_httpBasicUsername" class="form-control" value="${auth_httpBasicUsername}"/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">HTTP Basic Password</label>
                                <div class="col-sm-4">
                                    <input type="password" id="auth_httpBasicPassword" name="auth_httpBasicPassword" class="form-control" onchange="document.getElementById('auth_httpBasicPasswordChanged').value='true'" onkeyup="document.getElementById('auth_httpBasicPasswordChanged').value='true'" onpaste="document.getElementById('auth_httpBasicPasswordChanged').value='true'"/>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col">
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">Certificate Authentication</label>
                                <div class="col-sm-8" style="margin-top: 6px">
                                    <input type="checkbox" id="auth_certificateEnabled" name="auth_certificateEnabled" <c:if test="${true eq auth_certificateEnabled}">checked</c:if>/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">Use Custom Keystore</label>
                                <div class="col-sm-8" style="margin-top: 6px">
                                    <input type="checkbox" id="auth_useCustomKeyStore" name="auth_useCustomKeyStore" <c:if test="${true eq auth_useCustomKeyStore}">checked</c:if>/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">Keystore Location</label>
                                <div class="col-sm-7">
                                    <input type="text" id="auth_keyStoreLocation" name="auth_keyStoreLocation" class="form-control" value="${auth_keyStoreLocation}"/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">Keystore Password</label>
                                <div class="col-sm-4">
                                    <input type="password" id="auth_keyStorePassword" name="auth_keyStorePassword" class="form-control" onchange="document.getElementById('auth_keyStorePasswordChanged').value='true'" onkeyup="document.getElementById('auth_keyStorePasswordChanged').value='true'" onpaste="document.getElementById('auth_keyStorePasswordChanged').value='true'"/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">Key Alias</label>
                                <div class="col-sm-4">
                                    <input type="text" id="auth_keyAlias" name="auth_keyAlias" class="form-control" value="${auth_keyAlias}"/>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="attr_activationId" class="col-sm-4 control-label">Key Password</label>
                                <div class="col-sm-4">
                                    <input type="password" id="auth_keyPassword" name="auth_keyPassword" class="form-control" onchange="document.getElementById('auth_keyPasswordChanged').value='true'" onkeyup="document.getElementById('auth_keyPasswordChanged').value='true'" onpaste="document.getElementById('auth_keyPasswordChanged').value='true'"/>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="attr_activationId" class="col-sm-4 control-label">Use Custom Truststore</label>
                            <div class="col-sm-8" style="margin-top: 6px">
                                <input type="checkbox" id="auth_useCustomTrustStore" name="auth_useCustomTrustStore" <c:if test="${true eq auth_useCustomTrustStore}">checked</c:if>/>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="attr_activationId" class="col-sm-4 control-label">Truststore Location</label>
                            <div class="col-sm-7">
                                <input type="text" id="auth_trustStoreLocation" name="auth_trustStoreLocation" class="form-control" value="${auth_trustStoreLocation}"/>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="attr_activationId" class="col-sm-4 control-label">Truststore Password</label>
                            <div class="col-sm-4">
                                <input type="text" id="auth_trustStorePassword" name="auth_trustStorePassword" class="form-control" onchange="document.getElementById('auth_trustStorePasswordChanged').value='true'" onkeyup="document.getElementById('auth_trustStorePasswordChanged').value='true'" onpaste="document.getElementById('auth_trustStorePasswordChanged').value='true'"/>
                            </div>
                        </div>
                    </div>
                    <div class="form-group text-right">
                        <div class="col-sm-11">
                            <input type="hidden" name="auth_httpBasicPasswordChanged" id="auth_httpBasicPasswordChanged" value="false"/>
                            <input type="hidden" name="auth_keyStorePasswordChanged" id="auth_keyStorePasswordChanged" value="false"/>
                            <input type="hidden" name="auth_keyPasswordChanged" id="auth_keyPasswordChanged" value="false"/>
                            <input type="hidden" name="auth_trustStorePasswordChanged" id="auth_trustStorePasswordChanged" value="false"/>
                            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                            <input type="submit" value="Submit" class="btn btn-success"/>
                        </div>
                    </div>
                </form>
            </div>

        </div>
    </div>
    <div class="col-sm-5">
        <div class="panel panel-info">

            <div class="panel-heading">
                <h3 class="panel-title"><span class="glyphicon glyphicon-info-sign"></span> What are the callbacks?</h3>
            </div>

            <div class="panel-body">
                <p>
                    We will <span class="code">POST</span> a following JSON callback to the URL you
                    specify whenever an activation status changes.

                <pre class="code"><code class="json" id="callback_json"></code></pre>

                <p>
                    Callbacks can be authenticated by HTTP Basic authentication and/or certificate authentication.
                    Use the Java resource location format for specifying keystore and trustore locations, e.g.:
                    <pre class="code">file:/path_to_keystore</pre>
                    Passwords which are set on the server are not displayed in this form, however and indication
                    is provided for passwords which are set. Existing passwords are not changed when this form is
                    submitted unless the password value is changed.
            </div>

        </div>
    </div>
</div>

<jsp:include page="footer.jsp"/>
<jsp:include page="footerCallbacks.jsp"/>

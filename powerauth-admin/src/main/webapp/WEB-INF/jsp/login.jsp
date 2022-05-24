<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>PowerAuth Admin</title>
    <link rel="shortcut icon" href="${pageContext.request.contextPath}/resources/images/favicon.png">

    <!-- Bootstrap -->
    <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/css/bootstrap.min.css">
    <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/css/base.css">
    <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/css/lime-theme.min.css">
    <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/css/lime-login.css">
    <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/css/styles/xcode.css">

</head>
<body>

<div class="body">
    <div class="form-wrapper">
        <div class="container">

            <div class="form-panel">
                <c:if test="${param.error != null}">
                    <div class="alert alert-danger">
                        <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                        <strong>Error.</strong> Invalid username or password.
                    </div>
                </c:if>
                <c:if test="${param.logout != null}">
                    <div class="alert alert-info">
                        <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                        <strong>Success.</strong> You have been logged out.
                    </div>
                </c:if>
            </div>

            <div class="form-panel">
                <form class="form-signin" action="${pageContext.request.contextPath}/login" method="post" >
                    <div class="text-center form-logo-wrapper">
                        <img src="${pageContext.request.contextPath}/resources/images/logo.png" class="form-logo"/>
                    </div>
                    <p class="text-center lead" style="color: gray;">
                        Please sign in
                    </p>
                    <label for="username" class="sr-only">Username</label>
                    <input type="text" id="username" name="username" class="form-control" placeholder="Username" required autofocus />
                    <label for="inputPassword" class="sr-only">Password</label>
                    <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required />
                    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
                    <button class="btn btn-success btn-block" type="submit">Log in</button>
                </form>
            </div>

        </div>
    </div>
</div>


<script src="${pageContext.request.contextPath}/resources/js/jquery.min.js"></script>
<script src="${pageContext.request.contextPath}/resources/js/bootstrap.min.js"></script>
<script src="${pageContext.request.contextPath}/resources/js/base.js"></script>
<script src="${pageContext.request.contextPath}/resources/js/highlight.js"></script>
<script src="${pageContext.request.contextPath}/resources/js/clipboard.min.js"></script>
</body>
</html>
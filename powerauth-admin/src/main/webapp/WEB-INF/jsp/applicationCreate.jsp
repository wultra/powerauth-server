<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<jsp:include page="header.jsp">
    <jsp:param name="pageTitle" value="PowerAuth Admin - New Application"/>
</jsp:include>

<ol class="breadcrumb">
    <li><a class="black" href="${pageContext.request.contextPath}/application/list">Applications</a></li>
    <li class="active">New Application</li>
</ol>


<div class="panel panel-default">

    <div class="panel-heading">
        <h3 class="panel-title">New Application</h3>
    </div>

    <div class="panel-body">


        <form class="form-inline" action="${pageContext.request.contextPath}/application/create/do.submit" method="POST">
            Application ID <input type="text" name="id" class="form-control">
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input type="submit" value="Submit" class="btn btn-success"/>
            <c:if test="${not empty error}">
                <span style="color: #c0007f; margin-left: 10px;"><c:out value="${error}"/></span>
            </c:if>
        </form>
    </div>

</div>

<jsp:include page="footer.jsp"/>
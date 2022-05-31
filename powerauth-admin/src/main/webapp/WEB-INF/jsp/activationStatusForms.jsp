<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<c:if test="${not empty error}">
    <div style="color: #c0007f; margin-bottom: 5px; text-align: center"><c:out value="${error}"/></div>
</c:if>

<c:choose>
    <c:when test="${param.status == 'CREATED'}">
        <form action="${pageContext.request.contextPath}/activation/remove/do.submit" method="POST"
              class="pull-right action-remove">
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-danger btn-table" type="submit" value="Remove">
        </form>
    </c:when>
    <c:when test="${param.status == 'PENDING_COMMIT'}">
        <form action="${pageContext.request.contextPath}/activation/remove/do.submit" method="POST"
              class="pull-right action-remove">
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-danger btn-table" type="submit" value="Remove">
        </form>
        <form action="${pageContext.request.contextPath}/activation/commit/do.submit" method="POST" class="form-inline">
            <c:if test="${param.showOtpInput == true}">
                OTP: <input name="activationOtp" class="form-control" size="12"/>
            </c:if>
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-success btn-table pull-right" type="submit" value="Commit">
        </form>
    </c:when>
    <c:when test="${param.status == 'ACTIVE'}">
        <form action="${pageContext.request.contextPath}/activation/remove/do.submit" method="POST"
              class="pull-right action-remove">
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-danger btn-table" type="submit" value="Remove">
        </form>
        <form action="${pageContext.request.contextPath}/activation/block/do.submit" method="POST" class="pull-right">
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-warning btn-table" type="submit" value="Block">
        </form>
    </c:when>
    <c:when test="${param.status == 'BLOCKED'}">
        <form action="${pageContext.request.contextPath}/activation/remove/do.submit" method="POST"
              class="pull-right action-remove">
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-default btn-table" type="submit" value="Remove">
        </form>
        <form action="${pageContext.request.contextPath}/activation/unblock/do.submit" method="POST" class="pull-right">
            <input type="hidden" name="activationId" value="<c:out value="${param.activationId}"/>"/>
            <input type="hidden" name="redirectUserId" value="<c:out value="${param.redirectUserId}"/>"/>
            <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
            <input class="btn btn-danger btn-table" type="submit" value="Unblock">
        </form>
    </c:when>
</c:choose>
<div class="clearfix"></div>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>

<c:choose>
    <c:when test="${param.status == 'CREATED'}">
        <span class="green code">CREATED</span>
    </c:when>
    <c:when test="${param.status == 'PENDING_COMMIT'}">
        <span class="green code">PENDING_COMMIT</span>
    </c:when>
    <c:when test="${param.status == 'ACTIVE'}">
        <span class="green code">ACTIVE</span>
    </c:when>
    <c:when test="${param.status == 'BLOCKED'}">
        <span class="orange code">BLOCKED</span>
    </c:when>
    <c:when test="${param.status == 'REMOVED'}">
        <span class="red code">REMOVED</span>
    </c:when>
</c:choose>
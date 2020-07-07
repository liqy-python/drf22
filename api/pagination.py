from rest_framework.pagination import PageNumberPagination, LimitOffsetPagination, CursorPagination


# 基础分页器
class MyPageNumberPagination(PageNumberPagination):
    # 指定每页分页的数量
    page_size = 3
    # 可以通过此参数指定分页最大数量
    max_page_size = 5
    # 指定前端修改每页分页数量的 key
    page_size_query_param = "page_size"
    # 获取第几页的对象
    page_query_param = "page"


# 偏移分页器
class MyLimitPagination(LimitOffsetPagination):
    # 默认获取的每页数量
    default_limit = 3
    # 指定前端修改每页数量的key
    limit_query_param = "limit"
    # 前端指定偏移的数量的key
    offset_query_param = "offset"
    # 每页获取的最大数量
    max_limit = 5


# 游标分页器 (加密)
class MyCoursePagination(CursorPagination):
    cursor_query_param = 'cursor'
    page_size = 3
    page_size_query_param = "page_size"
    max_page_size = 5
    ordering = "-price"
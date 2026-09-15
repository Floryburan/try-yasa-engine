def user_detail(request, user_id):
    search = request.GET.get("search")
    return render_profile(user_id, search)


def render_profile(user_id, search):
    return {"user_id": user_id, "search": search}


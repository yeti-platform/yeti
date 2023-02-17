from fastapi import APIRouter

observables_router = APIRouter()


@observables_router.get('/')
async def observables_root():
    return {'message': 'Hello observables'}

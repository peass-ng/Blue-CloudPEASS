"""Scoped membership preserves exact published Check equality and identities."""
import ast
from dataclasses import replace
import inspect
from peaso.checks import CHECKS,CHECK_ALIASES
from peaso.checks import bulk_pending


def registrar_filter():
    tree=ast.parse(inspect.getsource(bulk_pending.install))
    comprehension=next(n for n in ast.walk(tree) if isinstance(n,ast.ListComp))
    return compile(ast.Expression(body=comprehension),'<bulk-isolated-membership>','eval')


def optimized(baseline,current,ident):
    by_id={}
    for check in baseline:by_id.setdefault(check.id,[]).append(check)
    if ident not in by_id:return current
    return eval(registrar_filter(),{'CHECKS':current,'ident':ident,'baseline':baseline,'baseline_by_id':by_id})


def test_filter_matches_original_for_every_published_and_admitted_check():
    baseline=tuple(CHECKS);aliases=dict(CHECK_ALIASES);before=tuple(CHECKS)
    for check in baseline:
        expected=[c for c in baseline if c.id!=check.id or c not in baseline]
        actual=optimized(baseline,list(baseline),check.id)
        assert [id(c)for c in actual]==[id(c)for c in expected]
    assert tuple(CHECKS)==before and CHECK_ALIASES==aliases


def test_equal_copy_same_id_different_callback_and_duplicate_ids_keep_equality_semantics():
    original=CHECKS[0]
    equal_copy=replace(original)
    other_callback=replace(original,evaluate=lambda item,index:('UNKNOWN',{}))
    unrelated=replace(original,id='unrelated')
    baseline=(original,other_callback)
    current=[original,equal_copy,other_callback,unrelated]
    expected=[c for c in current if c.id!=original.id or c not in baseline]
    assert [id(c)for c in optimized(baseline,current,original.id)]==[id(c)for c in expected]
    assert [id(c)for c in optimized(baseline,current,'unrelated')]==[id(c)for c in current]


def test_new_ids_skip_slice_scan_and_preserve_alias_cleanup_and_decorator():
    tree=ast.parse(inspect.getsource(bulk_pending.install))
    isolated=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='isolated')
    class TrackedList(list):
        writes=0
        def __setitem__(self,key,value):
            self.writes+=1
            super().__setitem__(key,value)
    original=CHECKS[0]
    for ident,expected_writes in [('new-id',0),(original.id,1)]:
        current=TrackedList([original,replace(original,id='new-id')]);before=list(current)
        aliases={ident:'legacy-alias'};calls=[]
        namespace={'CHECKS':current,'ident':ident,'baseline_by_id':{original.id:[original]},
                   'CHECK_ALIASES':dict(aliases),'aliases':aliases,'alias':'isolated-test',
                   'decorate':lambda fn:calls.append(fn) or fn}
        exec(compile(ast.Module(body=[isolated],type_ignores=[]),'<isolated-registrar>','exec'),namespace)
        def callback(item,index):return 'PASS',{}
        callback.__module__='isolated-test'
        assert namespace['isolated'](callback) is callback
        expected=[c for c in before if c.id!=ident or c not in (original,)]
        assert [id(c)for c in current]==[id(c)for c in expected]
        assert current.writes==expected_writes
        assert ident not in namespace['CHECK_ALIASES'] and calls==[callback]
